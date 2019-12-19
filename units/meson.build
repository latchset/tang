tangd_keygen_service = configure_file(
  input: 'tangd-keygen.service.in',
  output: 'tangd-keygen.service',
  configuration: data
)

tangd_service = configure_file(
  input: 'tangd@.service.in',
  output: 'tangd@.service',
  configuration: data
)

tangd_update_path = configure_file(
  input: 'tangd-update.path.in',
  output: 'tangd-update.path',
  configuration: data
)

tangd_update_service = configure_file(
  input: 'tangd-update.service.in',
  output: 'tangd-update.service',
  configuration: data
)

units += join_paths(meson.current_source_dir(), 'tangd.socket')
units += tangd_keygen_service
units += tangd_service
units += tangd_update_path
units += tangd_update_service

# vim:set ts=2 sw=2 et:
