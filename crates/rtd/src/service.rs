//! Integrazione con il Gestore servizi di Windows: avvio come servizio,
//! installazione e disinstallazione.

use std::{ffi::OsString, sync::Arc, time::Duration};

use vigil_engine::rtproto::{DRIVER_SERVICE_NAME, SERVICE_NAME};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceDependency, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{Options, start_protection};

define_windows_service!(ffi_service_main, service_main);

/// Chiamato da `vigil-rtd service`: consegna il controllo al Gestore servizi.
pub fn run_as_service() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| format!("avvio come servizio: {e}"))
}

fn service_main(args: Vec<OsString>) {
    if let Err(e) = run_service(args) {
        eprintln!("servizio terminato con errore: {e}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service(_args: Vec<OsString>) -> Result<(), String> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| e.to_string())?;

    handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty())).map_err(|e| e.to_string())?;
    // Le opzioni arrivano dagli argomenti registrati con `install` (dopo la parola "service").
    let mut opts = Options::parse(std::env::args().skip(2))?;
    opts.0.protect_install_dir = true;
    let shared = start_protection(opts)?;
    handle
        .set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN))
        .map_err(|e| e.to_string())?;

    let _ = stop_rx.recv();
    handle.set_service_status(status(ServiceState::StopPending, ServiceControlAccept::empty())).map_err(|e| e.to_string())?;
    shared.save_cache();
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
    // I thread di protezione sono infiniti: si esce dal processo.
    std::process::exit(0);
}

/// Registra il servizio (richiede l'amministratore). `args` sono le opzioni di protezione.
pub fn install(args: Vec<String>) -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| format!("Gestore servizi: {e} (serve l'amministratore)"))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut launch: Vec<OsString> = vec!["service".into()];
    launch.extend(args.into_iter().map(OsString::from));
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "Vigil - protezione in tempo reale".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: launch,
        // Avviando il servizio, Windows carica prima il driver.
        dependencies: vec![ServiceDependency::Service(DRIVER_SERVICE_NAME.into())],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS) {
        Ok(s) => {
            s.change_config(&info).map_err(|e| e.to_string())?;
            s
        }
        Err(_) => manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .map_err(|e| format!("creazione del servizio: {e}"))?,
    };
    let _ = service.set_description("Blocca l'esecuzione delle minacce e isola i file pericolosi appena scritti.");
    if !service.query_status().is_ok_and(|s| s.current_state == ServiceState::Running) {
        service.start::<&str>(&[]).map_err(|e| format!("avvio del servizio: {e}"))?;
    }
    println!("servizio {SERVICE_NAME} installato e avviato");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| e.to_string())?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("servizio non trovato: {e}"))?;
    if service.query_status().is_ok_and(|s| s.current_state == ServiceState::Running) {
        let _ = service.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    service.delete().map_err(|e| e.to_string())?;
    println!("servizio {SERVICE_NAME} rimosso");
    Ok(())
}

#[allow(dead_code)]
fn _assert_send(_: Arc<crate::state::Shared>) {}
