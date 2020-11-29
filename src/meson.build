tangd = executable('tangd',
  'http.c',
  'keys.c',
  'tangd.c',
  dependencies: [jose, http_parser],
  install: true,
  install_dir: libexecdir
)

bins += join_paths(meson.current_source_dir(), 'tang-show-keys')
libexecbins += join_paths(meson.current_source_dir(), 'tangd-keygen')
libexecbins += join_paths(meson.current_source_dir(), 'tangd-rotate-keys')

# vim:set ts=2 sw=2 et:
