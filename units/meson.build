tangd_service = configure_file(
  input: 'tangd@.service.in',
  output: 'tangd@.service',
  configuration: data
)
if build_machine.system() == 'freebsd'
  tangd_rc = configure_file(
    input: 'tangd.rc.in',
    output: 'tangd',
    configuration: data,
    install_dir: join_paths(get_option('prefix') + sysconfdir, 'rc.d'),
    install_mode: ['rwxr-xr-x', 'root', 'wheel']
  )
else
  units += join_paths(meson.current_source_dir(), 'tangd.socket')
  units += tangd_service
endif

# vim:set ts=2 sw=2 et:
