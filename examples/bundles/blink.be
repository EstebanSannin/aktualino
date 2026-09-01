#- aktualino-bundle: blink an LED on GPIO 2 once per second.
   GPIO 2 is the on-board LED on many ESP32 dev boards. -#
var BUNDLE = { "schema": 1, "version": "1.0.0", "requires_host_api": 1 }

var LED = 2
var last = 0
var state = 0

def setup()
  gpio_mode(LED, 1)      # 1 = OUTPUT
  gpio_set(LED, 0)
  log("blink: driving GPIO 2 once per second")
  health_ok()
end

def loop()
  # loop() runs every ~500ms; toggle when a second has elapsed (millis()).
  if millis() - last >= 1000
    last = millis()
    state = 1 - state    # 0 -> 1 -> 0
    gpio_set(LED, state)
    report("led", state)
  end
end
