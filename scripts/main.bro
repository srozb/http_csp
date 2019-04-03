module HTTP_CSP;

@load base/frameworks/notice/main
@load base/protocols/http

export {
	## If you would like to enable parser on every CSP request
    ## set this variable to T
	const HTTP_CSP::all_sites = T &redef;

    ## Otherwise you could specify sites to be monitored
    const HTTP_CSP::monitored_sites = set("") &redef;

    type csp_report: record {
        document_uri:               string      &log;
        referrer:                   string      &log &optional;
        violated_directive:         string      &log &optional;
        original_policy:            string      &optional;
        column_number:              string      &log &optional;
        line_number:                string      &log &optional;
        blocked_uri:                string      &log &optional;
    };

    global Report: event(c: connection, rec: csp_report);
}


function extract_between(buf: string, from: pattern, to: pattern): string {
	## never found a better way to do this.
	if (from !in buf || to !in buf) return "";
	buf = split_string1(buf, from)[1];
	buf = split_string1(buf, to)[0];
	return buf;
}

function is_monitored_csp_req(c: connection, data: string): bool {
    if ( !c$http?$host ) return F;
    if ( c$http$method != "POST" ) return F;
    if ( !HTTP_CSP::all_sites && c$http$host !in HTTP_CSP::monitored_sites ) return F;
    if ( /\"csp-report\":/ in data[:32] ) return T;
    return F;
}

function parse_report(buf: string): csp_report
{
    local r: csp_report;
    r$document_uri = extract_between(buf, /\"document-uri\"\:\"/, /\"/);
    r$referrer = extract_between(buf, /\"referrer\"\:\"/, /\"/);
    r$violated_directive = extract_between(buf, /\"violated-directive\"\:\"/, /\"/);
    r$original_policy = extract_between(buf, /\"original-policy\"\:\"/, /\"/);
    r$column_number = extract_between(buf, /\"column-number\":/, /,/);
    r$line_number = extract_between(buf, /\"line-number\":/, /,/);
    r$blocked_uri = extract_between(buf, /\"blocked-uri\"\:\"/, /\"/);
    return r;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if ( is_orig && is_monitored_csp_req(c, data) ) {
        local r = parse_report(data);
        event HTTP_CSP::Report(c, r);
    }
}
