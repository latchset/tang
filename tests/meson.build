sd_activate = find_program(
  'systemd-socket-activate',
  'systemd-activate',
  required: false
)

if sd_activate.found()
  env = environment()
  env.prepend('PATH',
    join_paths(meson.source_root(), 'src'),
    join_paths(meson.build_root(), 'src'),
    separator: ':'
  )
  env.set('SD_ACTIVATE', sd_activate.path() + ' --inetd')

  test('adv', find_program('adv'), env: env)
  test('rec', find_program('rec'), env: env)
else
  warning('Will not run the tests due to missing dependencies!')
endif

# vim:set ts=2 sw=2 et:
