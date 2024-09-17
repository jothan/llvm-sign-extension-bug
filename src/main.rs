#![feature(array_chunks)]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(clippy::large_futures)]

esp_idf_svc::sys::esp_app_desc!();
use esp_idf_svc::sys::{self, esp, EspError};
use esp_idf_svc::wifi::{AsyncWifi, ClientConfiguration, EspWifi};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop, hal::peripherals::Peripherals, nvs::EspDefaultNvsPartition,
    timer::EspTaskTimerService,
};
use std::ffi::CStr;
use std::ffi::{c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::NonNull;
use std::{ffi::CString, mem::ManuallyDrop, ops::DerefMut};

const EXECUTOR_STACK_SIZE: usize = 16364;

fn main() -> anyhow::Result<()> {
    let mounted_eventfs = init()?;

    // Copied from the TLS example. The main task priority is too low.
    // The stack size needs to be quite big.
    let _executor_thread = std::thread::Builder::new()
        .name("smol-main".into())
        .stack_size(EXECUTOR_STACK_SIZE)
        .spawn(|| run_main(mounted_eventfs))?;

    Ok(())
}

fn run_main(_mounted_eventfs: esp_idf_svc::io::vfs::MountedEventfs) -> anyhow::Result<()> {
    futures_lite::future::block_on(run_app())?;
    Ok(())
}

async fn run_app() -> anyhow::Result<()> {
    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let timer_service = EspTaskTimerService::new()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = AsyncWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs.clone()))?,
        sysloop.clone(),
        timer_service,
    )?;

    const WOKWI: bool = false;

    let cfg = if WOKWI {
        ClientConfiguration {
            ssid: "Wokwi-GUEST".try_into().unwrap(),
            auth_method: esp_idf_svc::wifi::AuthMethod::None,
            ..Default::default()
        }
    } else {
        ClientConfiguration {
            ssid: include_str!("../wifi-ssid").try_into().unwrap(),
            password: include_str!("../wifi-pass").try_into().unwrap(),
            auth_method: esp_idf_svc::wifi::AuthMethod::WPAWPA2Personal,
            ..Default::default()
        }
    };

    wifi.set_configuration(&esp_idf_svc::wifi::Configuration::Client(cfg))?;

    log::info!("Wi-Fi starting");
    wifi_disable_powersave()?;
    wifi.start().await?;
    wifi.connect().await?;

    wifi.ip_wait_while(
        |i| {
            let ip_info = i.wifi_mut().sta_netif().get_ip_info()?;
            log::info!("ip_info: {ip_info:?}");
            Ok(ip_info.ip.is_unspecified())
        },
        None,
    )
    .await?;
    log::info!("Wi-Fi connected");

    let name = Name::try_from("google.com").unwrap();
    // WOKWI filters AAAA records ??
    log::info!("v6: {:?}", resolve_ipv6(&name).await);
    log::info!("v4: {:?}", resolve_ipv4(&name).await);

    futures_lite::future::poll_fn(|_| std::task::Poll::Pending::<()>).await;
    Ok(())
}

pub fn init() -> anyhow::Result<esp_idf_svc::io::vfs::MountedEventfs> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // `async-io` uses the ESP IDF `eventfd` syscall to implement async IO.
    // If you use `tokio`, you still have to do the same as it also uses the `eventfd` syscall
    Ok(esp_idf_svc::io::vfs::MountedEventfs::mount(5)?)
}

pub fn extract_ip(value: &sys::esp_ip_addr_t) -> Option<IpAddr> {
    match value.type_ as _ {
        sys::ESP_IPADDR_TYPE_V4 => Some(
            Ipv4Addr::from(u32::from_be(unsafe { value.u_addr.ip4.addr }).to_be_bytes()).into(),
        ),
        sys::ESP_IPADDR_TYPE_V6 => Some(extract_ipv6(unsafe { value.u_addr.ip6.addr }).into()),
        _ => None,
    }
}

fn extract_ipv6(value: [u32; 4]) -> Ipv6Addr {
    let mut out = [0; 16];
    value
        .into_iter()
        .map(u32::from_be)
        .map(u32::to_be_bytes)
        .zip(out.array_chunks_mut())
        .for_each(|(i, o)| {
            *o = i;
        });

    Ipv6Addr::from(out)
}

pub fn wifi_disable_powersave() -> Result<(), EspError> {
    esp!(unsafe { sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE) })
}

const LWIP_DNS_ADDRTYPE_IPV4: u8 = 0;
const LWIP_DNS_ADDRTYPE_IPV6: u8 = 1;

extern "C" {
    fn dns_gethostbyname_addrtype(
        hostname: *const c_char,
        addr: *mut sys::esp_ip_addr_t,
        found: Option<
            unsafe extern "C" fn(
                name: *const c_char,
                ipaddr: Option<NonNull<sys::esp_ip_addr_t>>,
                callback_arg: *mut c_void,
            ),
        >,
        callback_arg: *mut c_void,
        dns_addrtype: u8,
    ) -> sys::err_t;
}

type IpSender = async_oneshot::Sender<Result<sys::esp_ip_addr_t, Error>>;

#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum Error {
    #[error("Invalid name")]
    InvalidName,
    #[error("DNS lookup error")]
    LookupError,
}

pub struct Name(CString);

impl TryFrom<&str> for Name {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_owned().try_into()
    }
}

impl TryFrom<String> for Name {
    type Error = Error;

    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        value.push(0 as char);
        Ok(Name(
            CString::from_vec_with_nul(value.into()).map_err(|_| Error::InvalidName)?,
        ))
    }
}

pub async fn resolve_ipv4(name: &Name) -> Result<Ipv4Addr, Error> {
    let ip = resolve(&name.0, LWIP_DNS_ADDRTYPE_IPV4).await?;
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        _ => Err(Error::LookupError),
    }
}

pub async fn resolve_ipv6(name: &Name) -> Result<Ipv6Addr, Error> {
    let ip = resolve(&name.0, LWIP_DNS_ADDRTYPE_IPV6).await?;
    match ip {
        IpAddr::V6(ip) => Ok(ip),
        _ => Err(Error::LookupError),
    }
}

/// Call resolve_raw from the TCP/IP thread
async fn resolve(name: &CStr, addr_type: u8) -> Result<IpAddr, Error> {
    let (tx, rx) = async_oneshot::oneshot();

    struct Ctx(*const c_char, u8, IpSender);
    unsafe impl Send for Ctx {}
    let mut ctx = ManuallyDrop::new(Ctx(name.as_ptr(), addr_type, tx));

    unsafe { sys::esp_netif_tcpip_exec(Some(cb), ctx.deref_mut() as *mut _ as *mut c_void) };

    unsafe extern "C" fn cb(ctx: *mut c_void) -> sys::esp_err_t {
        let Ctx(name, addr_type, tx) = unsafe { std::ptr::read(ctx as *mut Ctx) };
        unsafe { resolve_raw(name, addr_type, tx) };
        sys::ESP_OK
    }

    rx.await
        .map_err(|_| Error::LookupError)?
        .and_then(|ip| extract_ip(&ip).ok_or(Error::LookupError))
}

#[no_mangle]
unsafe fn resolve_raw(name: *const c_char, addr_type: u8, tx: IpSender) {
    let mut ip: sys::esp_ip_addr_t = Default::default();
    let tx: *mut IpSender = Box::into_raw(Box::new(tx));
    let ret = unsafe {
        dns_gethostbyname_addrtype(name, &mut ip, Some(cb), tx as *mut c_void, addr_type)
    };

    unsafe extern "C" fn cb(
        _name: *const c_char,
        ipaddr: Option<NonNull<sys::esp_ip_addr_t>>,
        callback_arg: *mut c_void,
    ) {
        let mut tx = unsafe { Box::from_raw(callback_arg as *mut IpSender) };
        let ipaddr = ipaddr
            .map(|ip| unsafe { ip.read() })
            .ok_or(Error::LookupError);
        let _ = tx.send(ipaddr);
    }

    //log::info!("ret: {ret}");

    // -5 gets "sign-extended" into 251 when doing i8 as i32
    // Codegen bug ? https://github.com/espressif/llvm-project/issues/102
    match sign_extender(ret) {
        sys::err_enum_t_ERR_OK => {
            let mut tx = unsafe { Box::from_raw(tx) };
            let _ = tx.send(Ok(ip));
        }
        sys::err_enum_t_ERR_INPROGRESS => (),
        sys::err_enum_t_ERR_ARG => {
            let mut tx = unsafe { Box::from_raw(tx) };
            let _ = tx.send(Err(Error::InvalidName));
        }
        v => {
            log::error!("crash: {v}");
            panic!("Unexpected result from DNS resolution system.");
        }
    }
}

#[inline(always)]
fn sign_extender(v: i8) -> i32 {
    v as i32
}
