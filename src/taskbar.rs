use std::collections::HashMap;

use forensic_rs::{core::UserEnvVars, err::ForensicResult, notifications::NotificationType, notify_info, traits::registry::{auto_close_key, extra::env_vars::get_env_vars_of_users, RegHiveKey, RegistryReader, HKU}};

use crate::common::{TaskBarApplication, TaskBarApplicationID};


pub fn read_task_bar_applications(registry : &dyn RegistryReader) -> ForensicResult<HashMap<TaskBarApplicationID, TaskBarApplication>> {
    let mut ret : HashMap<TaskBarApplicationID, TaskBarApplication> = HashMap::new();
    let mut env_vars = get_env_vars_of_users(registry)?;
    env_vars.remove("");
    for (user_sid, env_vars) in env_vars {
        let user_key = match registry.open_key(HKU, &user_sid) {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Cannot access HKEY_USERS\\{} registry key: {}", user_sid, e);
                continue
            }
        };
        let _ = auto_close_key(registry, user_key, || {
            let feature_usage = registry.open_key(user_key, r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage")?;
            process_feature_usage_update(registry, feature_usage, &user_sid, &mut ret, &env_vars);
            Ok(())
        });
    }
    Ok(ret)
}

fn process_feature_usage_update(registry : &dyn RegistryReader, key : RegHiveKey, user_sid : &str, applications : &mut HashMap<TaskBarApplicationID, TaskBarApplication>, env_vars : &UserEnvVars) {
    match registry.open_key(key, "AppBadgeUpdated") {
        Ok(app_badge_update) => {
            let _ = auto_close_key(registry, app_badge_update, || {
                process_app_badge_update(registry, app_badge_update, user_sid, applications, env_vars)
            });
        },
        Err(e) => {
            notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppBadgeUpdated registry key: {}", user_sid, e);
        }
    };
    match registry.open_key(key, "AppLaunch") {
        Ok(app_launch) => {
            let _ = auto_close_key(registry, app_launch, || {
                process_app_launch_update(registry, app_launch, user_sid, applications, env_vars)
            });
        },
        Err(e) => {
            notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch registry key: {}", user_sid, e);
        }
    };
    match registry.open_key(key, "AppSwitched") {
        Ok(app_launch) => {
            let _ = auto_close_key(registry, app_launch, || {
                process_app_switched_update(registry, app_launch, user_sid, applications, env_vars)
            });
        },
        Err(e) => {
            notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched registry key: {}", user_sid, e);
        }
    };
    match registry.open_key(key, "ShowJumpView") {
        Ok(app_launch) => {
            let _ = auto_close_key(registry, app_launch, || {
                process_jump_view_update(registry, app_launch, user_sid, applications, env_vars)
            });
        },
        Err(e) => {
            notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView registry key: {}", user_sid, e);
        }
    };
}

fn process_app_badge_update(registry : &dyn RegistryReader, key : RegHiveKey, user_sid : &str, applications : &mut HashMap<TaskBarApplicationID, TaskBarApplication>, env_vars : &UserEnvVars) -> ForensicResult<()> {
    let values = registry.enumerate_values(key)?;
    for value_name in values {
        if value_name.is_empty() {
            continue
        }
        let value = match registry.read_value(key, &value_name) {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppBadgeUpdated\\{} registry key: {}", user_sid, value_name, e);
                continue
            }
        };
        let badge_updates : u32 = match value.try_into() {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Invalid badge counter in HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppBadgeUpdated\\{} registry key must be a DWORD: {}", user_sid, value_name, e);
                continue
            }
        };
        let app_id = TaskBarApplicationID::resolve_executable_path(value_name, env_vars);
        applications.entry(app_id).and_modify(|v| {
            v.badge_updates = badge_updates;
        }).or_insert_with_key(|key| {
            TaskBarApplication {
                id : key.clone(),
                app_switched : 0,
                badge_updates,
                executed_times : 0,
                show_jump_clicks : 0,
                tray_clicks : 0
            }
        });
    }
    Ok(())
}

fn process_app_launch_update(registry : &dyn RegistryReader, key : RegHiveKey, user_sid : &str, applications : &mut HashMap<TaskBarApplicationID, TaskBarApplication>, env_vars : &UserEnvVars) -> ForensicResult<()> {
    let values = registry.enumerate_values(key)?;
    for value_name in values {
        if value_name.is_empty() {
            continue
        }
        let value = match registry.read_value(key, &value_name) {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch\\{} registry key: {}", user_sid, value_name, e);
                continue
            }
        };
        let executed_times : u32 = match value.try_into() {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Invalid launch counter in HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch\\{} registry key must be a DWORD: {}", user_sid, value_name, e);
                continue
            }
        };
        let app_id = TaskBarApplicationID::resolve_executable_path(value_name, env_vars);
        applications.entry(app_id).and_modify(|v| {
            v.executed_times = executed_times;
        }).or_insert_with_key(|key| {
            TaskBarApplication {
                id : key.clone(),
                app_switched : 0,
                badge_updates : 0,
                executed_times,
                show_jump_clicks : 0,
                tray_clicks : 0
            }
        });
    }
    Ok(())
}

fn process_app_switched_update(registry : &dyn RegistryReader, key : RegHiveKey, user_sid : &str, applications : &mut HashMap<TaskBarApplicationID, TaskBarApplication>, env_vars : &UserEnvVars) -> ForensicResult<()> {
    let values = registry.enumerate_values(key)?;
    for value_name in values {
        if value_name.is_empty() {
            continue
        }
        let value = match registry.read_value(key, &value_name) {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\{} registry key: {}", user_sid, value_name, e);
                continue
            }
        };
        let app_switched : u32 = match value.try_into() {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Invalid launch counter in HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\{} registry key must be a DWORD: {}", user_sid, value_name, e);
                continue
            }
        };
        let app_id = TaskBarApplicationID::resolve_executable_path(value_name, env_vars);
        applications.entry(app_id).and_modify(|v| {
            v.app_switched = app_switched;
        }).or_insert_with_key(|key| {
            TaskBarApplication {
                id : key.clone(),
                app_switched,
                badge_updates : 0,
                executed_times : 0,
                show_jump_clicks : 0,
                tray_clicks : 0
            }
        });
    }
    Ok(())
}

fn process_jump_view_update(registry : &dyn RegistryReader, key : RegHiveKey, user_sid : &str, applications : &mut HashMap<TaskBarApplicationID, TaskBarApplication>, env_vars : &UserEnvVars) -> ForensicResult<()> {
    let values = registry.enumerate_values(key)?;
    for value_name in values {
        if value_name.is_empty() {
            continue
        }
        let value = match registry.read_value(key, &value_name) {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Cannot get HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView\\{} registry key: {}", user_sid, value_name, e);
                continue
            }
        };
        let show_jump_clicks : u32 = match value.try_into() {
            Ok(v) => v,
            Err(e) => {
                notify_info!(NotificationType::DeletedArtifact, "Invalid launch counter in HKEY_USERS\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView\\{} registry key must be a DWORD: {}", user_sid, value_name, e);
                continue
            }
        };
        let app_id = TaskBarApplicationID::resolve_executable_path(value_name, env_vars);
        applications.entry(app_id).and_modify(|v| {
            v.show_jump_clicks = show_jump_clicks;
        }).or_insert_with_key(|key| {
            TaskBarApplication {
                id : key.clone(),
                app_switched: 0,
                badge_updates : 0,
                executed_times : 0,
                show_jump_clicks,
                tray_clicks : 0
            }
        });
    }
    Ok(())
}
