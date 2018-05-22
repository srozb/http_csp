module HTTP_CSP;

@load ./main.bro

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                 time                    &log;
        id:                 conn_id                 &log;
        uid:                string                  &log;
        csp_report:         HTTP_CSP::csp_report    &log;
    };
}

event bro_init() {
    Log::create_stream(HTTP_CSP::LOG, [$columns=Info, $path="csp_report"]);
}

event HTTP_CSP::Report(c: connection, rec: csp_report) {
        local l: HTTP_CSP::Info;
        Log::write(HTTP_CSP::LOG, [
            $ts = c$start_time,
            $id = c$id,
            $uid = c$http$uid,
            $csp_report = rec
        ]);
}
