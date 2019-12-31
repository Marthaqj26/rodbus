use super::*;

unsafe fn get_callback_session<'a>(
    session: *mut Session,
) -> (&'a mut tokio::runtime::Runtime, CallbackSession) {
    let s = session.as_mut().unwrap();
    let runtime = s.runtime.as_mut().unwrap();
    let channel = s.channel.as_mut().unwrap();

    let session = CallbackSession::new(channel.create_session(
        UnitId::new(s.unit_id),
        std::time::Duration::from_millis(s.timeout_ms as u64),
    ));

    (runtime, session)
}

unsafe fn callback_to_fn<T>(
    context: *mut c_void,
    callback: Option<unsafe extern "C" fn(Result, *const T, usize, *mut c_void)>,
) -> impl Fn(std::result::Result<Vec<rodbus::types::Indexed<T>>, rodbus::error::Error>) -> ()
where
    T: Copy,
{
    let storage = ContextStorage { context };
    move |result| {
        if let Some(cb) = callback {
            match result {
                Err(err) => cb(err.kind().into(), null(), 0, storage.context),
                Ok(values) => {
                    let transformed: Vec<T> = values.iter().map(|x| x.value).collect();
                    cb(
                        Result::status(Status::Ok),
                        transformed.as_ptr(),
                        transformed.len(),
                        storage.context,
                    )
                }
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn read_coils_cb(
    session: *mut Session,
    start: u16,
    count: u16,
    callback: Option<unsafe extern "C" fn(Result, *const bool, usize, *mut c_void)>,
    context: *mut c_void,
) {
    let (runtime, mut session) = get_callback_session(session);
    session.read_coils(
        runtime,
        AddressRange::new(start, count),
        callback_to_fn(context, callback),
    );
}

#[no_mangle]
pub unsafe extern "C" fn read_discrete_inputs_cb(
    session: *mut Session,
    start: u16,
    count: u16,
    callback: Option<unsafe extern "C" fn(Result, *const bool, usize, *mut c_void)>,
    context: *mut c_void,
) {
    let (runtime, mut session) = get_callback_session(session);
    session.read_discrete_inputs(
        runtime,
        AddressRange::new(start, count),
        callback_to_fn(context, callback),
    );
}

#[no_mangle]
pub unsafe extern "C" fn read_holding_registers_cb(
    session: *mut Session,
    start: u16,
    count: u16,
    callback: Option<unsafe extern "C" fn(Result, *const u16, usize, *mut c_void)>,
    context: *mut c_void,
) {
    let (runtime, mut session) = get_callback_session(session);
    session.read_holding_registers(
        runtime,
        AddressRange::new(start, count),
        callback_to_fn(context, callback),
    );
}

#[no_mangle]
pub unsafe extern "C" fn read_input_registers_cb(
    session: *mut Session,
    start: u16,
    count: u16,
    callback: Option<unsafe extern "C" fn(Result, *const u16, usize, *mut c_void)>,
    context: *mut c_void,
) {
    let (runtime, mut session) = get_callback_session(session);
    session.read_input_registers(
        runtime,
        AddressRange::new(start, count),
        callback_to_fn(context, callback),
    );
}