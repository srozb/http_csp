# HTTP CSP Parser

## Package functionality and architecture

This package will:

* Parse HTTP `Content-Security-Policy` reports. After parsing is done it will fire an `HTTP_CSP::Report` event that can be used later to extend basic functionality,
* Log every (or only some) report to `csp_report.log` file,
* Use Bro Intelligence Framework to cross check domains in `blocked-uri` field against your threat intel.

Package contains 3 modules:

* `main.bro` - required,
* `logger.bro` - optional,
* `intel.bro` - optional.

You can skip loading optional files in case you don't want to log reports or use intel framework.

## tunables

You can also redefine following constants to customize package behaviour.

* `HTTP_CSP::all_sites` - parse every report seen (look for `csp-report` keyword in every HTTP POST request),
* `HTTP_CSP::monitored_sites` - parse only reports sent to specified hosts.
