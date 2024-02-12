incdir = include_directories(
  join_paths('..', 'src')
)

test_data = configuration_data()
test_data.set('testjwkdir', join_paths(meson.source_root(), 'tests','keys'))

test_keys_c = configure_file(
  input: 'test-keys.c.in',
  output: 'test-keys.c',
  configuration: test_data
)

test_keys = executable('test-keys',
  test_keys_c,
  'test-util.c',
  dependencies: [jose],
  include_directories: incdir
)

socat = find_program(
  'socat',
  required: false
)

env = environment()
env.prepend('PATH',
  join_paths(meson.source_root(), 'src'),
  join_paths(meson.build_root(), 'src'),
  join_paths(meson.source_root(), 'tests'),
  join_paths(meson.build_root(), 'tests'),
  separator: ':'
)

if host_machine.system() == 'freebsd'
  env.set('TANG_BSD', '1')
endif

if socat.found()
  env.set('SOCAT', socat.path())
endif

test('adv-standalone', find_program('adv-standalone'), env: env, timeout: 360)
test('adv-standalone-endpoint', find_program('adv-standalone-endpoint'), env: env, timeout: 360)
test('adv-socat', find_program('adv-socat'), env: env, timeout: 360)
test('adv-socat-endpoint', find_program('adv-socat-endpoint'), env: env, timeout: 360)
test('rec-standalone', find_program('rec-standalone'), env: env, timeout: 360)
test('rec-standalone-endpoint', find_program('rec-standalone-endpoint'), env: env, timeout: 360)
test('rec-socat', find_program('rec-socat'), env: env, timeout: 360)
test('rec-socat-endpoint', find_program('rec-socat-endpoint'), env: env, timeout: 360)
test('test-keys', test_keys, env: env, timeout: 360)

# vim:set ts=2 sw=2 et:
