/^# Packages using this file: / {
  s/# Packages using this file://
  ta
  :a
  s/ gnu-radius / gnu-radius /
  tb
  s/ $/ gnu-radius /
  :b
  s/^/# Packages using this file:/
}
