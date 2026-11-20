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

test_pqc_noop = executable('test-pqc-noop',
  'test-pqc-noop.c',
  'test-util.c',
  dependencies: [jose],
  include_directories: incdir
)

if has_pqc
  # A tangd built with the noop PQC handlers, so the hidden-endpoint
  # behavior can be exercised even when jose supports ML-KEM.
  tangd_noop = executable('tangd-noop',
    tangd_core_sources,
    pqc_noop_sources,
    dependencies: [jose, http_parser]
  )

  # A tangd whose runtime ML-KEM probe always fails (jose_jwk_gen is
  # wrapped to fail), so the runtime-unavailable paths of a PQC build
  # (uniform 404s, hybrid_recovery:false, the one-time startup log)
  # are exercised even on machines whose jose fully supports ML-KEM.
  tangd_unavailable = executable('tangd-unavailable',
    tangd_core_sources,
    pqc_sources,
    'wrap-jose-jwk-gen.c',
    dependencies: [jose, http_parser, libcrypto],
    link_args: ['-Wl,--wrap=jose_jwk_gen']
  )
endif

if has_pqc
  test_pqc_c = configure_file(
    input: 'test-pqc.c.in',
    output: 'test-pqc.c',
    configuration: test_data
  )

  test_pqc = executable('test-pqc',
    test_pqc_c,
    'test-util.c',
    dependencies: [jose, libcrypto],
    include_directories: incdir
  )
endif

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

# Tell the e2e tests whether the tangd build has PQC support, so their
# KEM sections follow the build instead of the jose CLI: the two
# disagree when PQC is explicitly disabled (-Dpqc=disabled) on a
# machine whose jose still supports ML-KEM.
env.set('TANG_HAS_PQC', has_pqc ? '1' : '0')

test('adv-standalone', find_program('adv-standalone'), env: env, timeout: 360)
test('adv-standalone-endpoint', find_program('adv-standalone-endpoint'), env: env, timeout: 360)
test('adv-socat', find_program('adv-socat'), env: env, timeout: 360)
test('adv-socat-endpoint', find_program('adv-socat-endpoint'), env: env, timeout: 360)
test('rec-standalone', find_program('rec-standalone'), env: env, timeout: 360)
test('rec-standalone-endpoint', find_program('rec-standalone-endpoint'), env: env, timeout: 360)
test('rec-socat', find_program('rec-socat'), env: env, timeout: 360)
test('rec-socat-endpoint', find_program('rec-socat-endpoint'), env: env, timeout: 360)
test('test-keys', test_keys, env: env, timeout: 360)
test('test-pqc-noop', test_pqc_noop, env: env, timeout: 360)
test('keygen', find_program('keygen'), env: env, timeout: 360)
test('rotate-keys', find_program('rotate-keys'), env: env, timeout: 360)
test('noop', find_program('noop'), env: env, timeout: 360)
test('errors', find_program('errors'), env: env, timeout: 360)

if has_pqc
  test('test-pqc', test_pqc, env: env, timeout: 360)
  test('unavailable', find_program('unavailable'), env: env, timeout: 360)
endif

# vim:set ts=2 sw=2 et:
