pqc_source = has_pqc ? 'pqc.c' : 'pqc_noop.c'
pqc_args = []
if has_explicit_bzero
  pqc_args += ['-DHAVE_EXPLICIT_BZERO']
endif

tangd = executable('tangd',
  'http.c',
  'keys.c',
  'tangd.c',
  'socket.c',
  pqc_source,
  c_args: pqc_args,
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
