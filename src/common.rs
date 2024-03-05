use forensic_rs::{core::UserEnvVars, utils::win::csidl::interpolate_csidl_path};

#[derive(Clone, Debug)]
pub struct TaskBarApplication {
    pub id : TaskBarApplicationID,
    /// Number of times a running application has its badge icon updated (for example, to notify you of unread emails or notifications)
    pub badge_updates : u32,
    /// Number of times an application pinned to the taskbar was run.
    pub executed_times : u32,
    /// Number of times an application switched focus (was left-clicked on the taskbar). shows the number of times the application was minimized or maximized, as opposed to just launched.
    pub app_switched : u32,
    /// Number of times an application was right-clicked on the taskbar
    pub show_jump_clicks : u32,
    /// Number of times built-in taskbar buttons were clicked (e.g., clock, Start button, etc.)
    pub tray_clicks : u32
}


#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TaskBarApplicationID {
    /// A program that follows the AUMID format
    AUMID(String),
    /// Executable path fully resolved
    Executable(String),
    /// A path that includes a CSIDL and cannot be resolved
    CsidlPath(String),
    /// A process that used the taskbar without AUMID. Ex: 
    Process(u32),
}

impl From<String> for TaskBarApplicationID {
    fn from(value: String) -> Self {
        if value.starts_with("*PID") {
            return Self::from_pid(value)
        }
        if value.contains('\\') ||value.contains('/') {
            Self::CsidlPath(value)
        }else{
            Self::AUMID(value)
        }
    }
}
impl From<&str> for TaskBarApplicationID {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

impl TaskBarApplicationID {
    pub fn from_pid(path : String) -> Self {
        if !path.starts_with("*PID") {
            return Self::AUMID(path)
        }
        if let Ok(pid) = decode_hex_process(&path[4..]) {
            return Self::Process(pid);
        }
        Self::AUMID(path)
    }
    /// Gets the full path resolving GUIDs and environment variables
    /// https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
    pub fn resolve_executable_path(mut path : String, env_vars : &UserEnvVars) -> Self {
        if path.starts_with("*PID") {
            return Self::from_pid(path)
        }
        if !(path.contains('\\') || path.contains('/')) {
            return Self::AUMID(path) 
        }
        match interpolate_csidl_path(&mut path, env_vars) {
            None => {
                Self::CsidlPath(path)
            },
            Some(v) => {
                Self::Executable(v)
            }
        }
    }
}
fn decode_hex_process(s: &str) -> Result<u32, std::num::ParseIntError> {
    let mut res = 0;
    let ln = s.len() - 1;
    for i in (0..s.len()).rev() {
        let a = u8::from_str_radix(&s[i..i + 1], 16)? as u32;
        if a == 0 {
            continue
        }
        res += a *  ( 1 << (4 * (ln - i) as u32));
    }
    Ok(res)
}

#[test]
fn should_parse_application_id() {
    assert_eq!(TaskBarApplicationID::Process(3996), "*PID00000f9c".into());
    assert_eq!(TaskBarApplicationID::AUMID("com.squirrel.Discord.Discord".into()), "com.squirrel.Discord.Discord".into());
    assert_eq!(TaskBarApplicationID::CsidlPath(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe".into()), r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe".into());
    let mut env_vars = UserEnvVars::new();
    env_vars.insert("APPDATA".into(), "C:\\ProgramData".into());
    env_vars.insert("LOCALAPPDATA".into(), "%USERPROFILE%\\AppData\\Local".into());
    env_vars.insert("ProgramFiles".into(), "C:\\Program Files".into());
    env_vars.insert("USERPROFILE".into(), "C:\\Users\\tester".into());
    env_vars.insert("windir".into(), "C:\\Windows".into());
    assert_eq!(TaskBarApplicationID::Executable(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".into()), TaskBarApplicationID::resolve_executable_path(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe".into(), &env_vars));
    assert_eq!(TaskBarApplicationID::Executable(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".into()), TaskBarApplicationID::resolve_executable_path(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".into(), &env_vars));
}