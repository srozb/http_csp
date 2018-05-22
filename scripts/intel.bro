module Intel;

@load ./main.bro
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

export {
    redef enum Intel::Where += {
        CSP_REPORT
    };
}


event HTTP_CSP::Report(c: connection, rec: HTTP_CSP::csp_report) {
    local domain: string;
    if (/:\/\// !in rec$blocked_uri) return;
    domain = split_string(rec$blocked_uri, /\//)[2];
    Intel::seen([
        $indicator = domain,
        $indicator_type = Intel::DOMAIN,
        $where = Intel::CSP_REPORT,
        $conn = c]);
}
