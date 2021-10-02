tangd = executable('tangd',
  'http.c',
  'keys.c',
  'tangd.c',
  dependencies: [jose, http_parser],
  install: true,
  install_dir: libexecdir
)

tangd_keygen = configure_file(
  input: 'tangd-keygen.in',
  output: 'tangd-keygen',
  configuration: data,
  install: true,
  install_dir: libexecdir
)

tangd_rotate_keys = configure_file(
  input: 'tangd-rotate-keys.in',
  output: 'tangd-rotate-keys',
  configuration: data,
  install: true,
  install_dir: libexecdir
)

bins += join_paths(meson.current_source_dir(), 'tang-show-keys')

# vim:set ts=2 sw=2 et:
