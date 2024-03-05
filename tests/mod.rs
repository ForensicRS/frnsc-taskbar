use forensic_rs::utils::testing::init_testing_logger;

#[test]
#[cfg(target_os="windows")]
fn should_compile() {
    init_testing_logger();
    let registry = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let taskbar = frnsc_taskbar::taskbar::read_task_bar_applications(&registry).unwrap();
    for (_app_id, app) in taskbar {
        println!("{:?}", app);
    }
}