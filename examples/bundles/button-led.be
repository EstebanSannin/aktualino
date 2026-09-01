#- aktualino-bundle: mirror the BOOT button (GPIO 0) onto an LED (GPIO 2).
   Demonstrates reading an input. GPIO 0 is active-low (reads 0 when pressed). -#
var BUNDLE = { "schema": 1, "version": "1.0.0", "requires_host_api": 1 }

var BTN = 0
var LED = 2

def setup()
  gpio_mode(BTN, 2)      # 2 = INPUT with pull-up
  gpio_mode(LED, 1)      # 1 = OUTPUT
  log("button->led: press BOOT to light GPIO 2")
  health_ok()
end

def loop()
  if gpio_get(BTN) == 0  # pressed (active-low)
    gpio_set(LED, 1)
  else
    gpio_set(LED, 0)
  end
end
