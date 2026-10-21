//! JNI bridge for app.payesh.NativeEngine. The exported symbols of the old C++ library are kept
//! byte-for-byte compatible (sha256File, scanner*), so every Kotlin caller keeps working unchanged.
mod engine;
mod integrity;
mod watch;

use jni::objects::{JByteArray, JObject, JObjectArray, JString};
use jni::sys::{jdouble, jint, jintArray, jlong, jobjectArray, jstring};
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;

use engine::Scanner;
use watch::Watch;

/// A panic must never unwind into the JVM.
fn guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

fn strings_to_java(env: &mut JNIEnv, v: &[String]) -> jobjectArray {
    let arr = match env.new_object_array(v.len() as jint, "java/lang/String", JObject::null()) {
        Ok(a) => a,
        Err(_) => return null_mut(),
    };
    for (i, s) in v.iter().enumerate() {
        if let Ok(js) = env.new_string(s) {
            let _ = env.set_object_array_element(&arr, i as jint, &js);
            let _ = env.delete_local_ref(js);
        }
    }
    arr.into_raw()
}

// ------------------------------------------------------------------ hashing / scanning

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_sha256File<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, jpath: JString<'l>,
) -> jstring {
    guard(null_mut(), || {
        if jpath.as_raw().is_null() {
            return null_mut();
        }
        let path: String = match env.get_string(&jpath) {
            Ok(s) => s.into(),
            Err(_) => return null_mut(),
        };
        match engine::sha256_file(&path) {
            Some(h) => env.new_string(h).map(|s| s.into_raw()).unwrap_or(null_mut()),
            None => null_mut(),
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerCreate<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, jpats: JObjectArray<'l>,
) -> jlong {
    guard(0, || {
        let mut pats: Vec<String> = Vec::new();
        if !jpats.as_raw().is_null() {
            let n = env.get_array_length(&jpats).unwrap_or(0).min(50_000);
            for i in 0..n {
                let o = match env.get_object_array_element(&jpats, i) {
                    Ok(o) => o,
                    Err(_) => {
                        pats.push(String::new());
                        continue;
                    }
                };
                if o.as_raw().is_null() {
                    pats.push(String::new());
                    continue;
                }
                let js = JString::from(o);
                let s: String = env.get_string(&js).map(String::from).unwrap_or_default();
                let _ = env.delete_local_ref(js);
                pats.push(s);
            }
        }
        Box::into_raw(Box::new(Scanner::new(&pats))) as jlong
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerFeed<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, h: jlong, arr: JByteArray<'l>, len: jint,
) {
    guard((), || {
        if h == 0 || arr.as_raw().is_null() || len <= 0 {
            return;
        }
        let n = env.get_array_length(&arr).unwrap_or(0).min(len);
        if n <= 0 {
            return;
        }
        let mut buf = vec![0i8; n as usize];
        if env.get_byte_array_region(&arr, 0, &mut buf).is_err() {
            return;
        }
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
        if let Some(s) = unsafe { (h as *mut Scanner).as_mut() } {
            s.feed(bytes);
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerMatches<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, h: jlong,
) -> jintArray {
    guard(null_mut(), || {
        let m: Vec<i32> = match unsafe { (h as *const Scanner).as_ref() } {
            Some(s) => s.matches().to_vec(),
            None => Vec::new(),
        };
        match env.new_int_array(m.len() as jint) {
            Ok(a) => {
                if !m.is_empty() {
                    let _ = env.set_int_array_region(&a, 0, &m);
                }
                a.into_raw()
            }
            Err(_) => null_mut(),
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerEntropy<'l>(
    _env: JNIEnv<'l>, _this: JObject<'l>, h: jlong,
) -> jdouble {
    guard(0.0, || unsafe { (h as *const Scanner).as_ref() }.map(|s| s.entropy()).unwrap_or(0.0))
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerBytes<'l>(
    _env: JNIEnv<'l>, _this: JObject<'l>, h: jlong,
) -> jlong {
    guard(0, || unsafe { (h as *const Scanner).as_ref() }.map(|s| s.bytes() as jlong).unwrap_or(0))
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_scannerFree<'l>(
    _env: JNIEnv<'l>, _this: JObject<'l>, h: jlong,
) {
    guard((), || {
        if h != 0 {
            drop(unsafe { Box::from_raw(h as *mut Scanner) });
        }
    })
}

// ------------------------------------------------------------------ real-time watcher

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_watchCreate<'l>(_env: JNIEnv<'l>, _this: JObject<'l>) -> jlong {
    guard(0, || match Watch::new() {
        Some(w) => Box::into_raw(Box::new(w)) as jlong,
        None => 0,
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_watchAdd<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, h: jlong, jpath: JString<'l>,
) -> jint {
    guard(-1, || {
        let w = match unsafe { (h as *const Watch).as_ref() } {
            Some(w) => w,
            None => return -1,
        };
        let path: String = match env.get_string(&jpath) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        w.add(&path)
    })
}

/// Blocks up to `timeout_ms`. Returns null when the watcher was woken for shutdown.
#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_watchNext<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>, h: jlong, timeout_ms: jint,
) -> jobjectArray {
    guard(null_mut(), || {
        let w = match unsafe { (h as *const Watch).as_ref() } {
            Some(w) => w,
            None => return null_mut(),
        };
        match w.next(timeout_ms) {
            Some(v) => strings_to_java(&mut env, &v),
            None => null_mut(),
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_watchWake<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, h: jlong) {
    guard((), || {
        if let Some(w) = unsafe { (h as *const Watch).as_ref() } {
            w.wake();
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_watchFree<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, h: jlong) {
    guard((), || {
        if h != 0 {
            drop(unsafe { Box::from_raw(h as *mut Watch) });
        }
    })
}

// ------------------------------------------------------------------ system integrity indicators

#[no_mangle]
pub extern "system" fn Java_app_payesh_NativeEngine_integrityProbe<'l>(mut env: JNIEnv<'l>, _this: JObject<'l>) -> jobjectArray {
    guard(null_mut(), || {
        let v = integrity::probe();
        strings_to_java(&mut env, &v)
    })
}
