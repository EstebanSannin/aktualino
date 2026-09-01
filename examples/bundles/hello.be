#- aktualino-bundle: hello — logs on start, reports an uptime counter.
   The simplest useful bundle. Uses only the S3 host API (log/report/health_ok). -#
var BUNDLE = { "schema": 1, "version": "1.0.0", "requires_host_api": 1 }

var ticks = 0

def setup()
  log("hello from the Berry secondary")
  health_ok()            # signal we started cleanly
end

def loop()
  ticks = ticks + 1
  if ticks % 10 == 0     # scheduler ticks every 500ms -> ~every 5s
    report("ticks", ticks)
  end
end
