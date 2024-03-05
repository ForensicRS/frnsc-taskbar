# Windows TaskBar Parser [Alpha]

Uses [ForensicRs](https://github.com/ForensicRS/frnsc-rs) framework.


```rust
let registry = frnsc_liveregistry_rs::LiveRegistryReader::new();
let taskbar_apps = frnsc_taskbar::taskbar::read_task_bar_applications(&registry).unwrap();
for (_app_id, app) in taskbar_apps {
    println!("{:?}", app);
}
```

Output: 

```
TaskBarApplication { id: AUMID("windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"), badge_updates: 0, executed_times: 0, app_switched: 46, show_jump_clicks: 0, tray_clicks: 0 }
TaskBarApplication { id: Executable("C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"), badge_updates: 0, executed_times: 0, app_switched: 1, show_jump_clicks: 0, tray_clicks: 0 }
TaskBarApplication { id: Process(32540), badge_updates: 0, executed_times: 0, app_switched: 2, show_jump_clicks: 0, tray_clicks: 0 }
TaskBarApplication { id: AUMID("microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"), badge_updates: 16, executed_times: 0, app_switched: 0, show_jump_clicks: 0, tray_clicks: 0 }
TaskBarApplication { id: AUMID("Brave"), badge_updates: 3, executed_times: 2, app_switched: 3, show_jump_clicks: 2, tray_clicks: 0 }
TaskBarApplication { id: Executable("C:\\Program Files\\Electronic Arts\\EA Desktop\\EA Desktop\\EADesktop.exe"), badge_updates: 62, executed_times: 0, app_switched: 3, show_jump_clicks: 2, tray_clicks: 0 }
```