# Sources of the tangd daemon, declared here (the directory that owns
# them) with files() so the paths are recorded as absolute. The
# test-only tangd variants in tests/meson.build reuse these variables
# instead of reaching into this directory with ../ paths.
tangd_core_sources = files('http.c', 'keys.c', 'tangd.c', 'socket.c')
pqc_sources = files('pqc.c')
pqc_noop_sources = files('pqc_noop.c')

pqc_source = has_pqc ? pqc_sources : pqc_noop_sources

tangd_deps = [jose, http_parser]
if has_pqc
  tangd_deps += libcrypto
endif

tangd = executable('tangd',
  tangd_core_sources,
  pqc_source,
  dependencies: tangd_deps,
  install: true,
  install_dir: libexecdir
)

tangd_utils = configure_file(
  input: 'tangd-utils.sh',
  output: 'tangd-utils.sh',
  copy: true,
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
