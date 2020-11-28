tangd_service = configure_file(
  input: 'tangd@.service.in',
  output: 'tangd@.service',
  configuration: data
)

units += join_paths(meson.current_source_dir(), 'tangd.socket')
units += tangd_service

# vim:set ts=2 sw=2 et:
