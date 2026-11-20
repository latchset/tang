project('tang', 'c',
  version: '16',
  license: 'GPL3+',
  default_options: [
    'c_std=c99',
    'prefix=/usr',
    'sysconfdir=/etc',
    'localstatedir=/var',
    'warning_level=3',
    'werror=true'
  ]
)

libexecdir = join_paths(get_option('prefix'), get_option('libexecdir'))
sysconfdir = join_paths(get_option('prefix'), get_option('sysconfdir'))
bindir = join_paths(get_option('prefix'), get_option('bindir'))
systemunitdir = join_paths(get_option('prefix'), 'lib/systemd/system')
licensedir = join_paths(get_option('prefix'), 'share', 'licenses', meson.project_name())
if host_machine.system() == 'freebsd'
  licensedir += '-'+meson.project_version()
endif
jwkdir = join_paths(get_option('localstatedir'), 'db', meson.project_name())

data = configuration_data()
data.set('libexecdir', libexecdir)
data.set('sysconfdir', sysconfdir)
data.set('systemunitdir', systemunitdir)
data.set('jwkdir', jwkdir)
data.set('user', get_option('user'))
data.set('group', get_option('group'))

add_project_arguments(
  '-D_POSIX_C_SOURCE=200809L',
  '-Wstrict-aliasing',
  '-Wchar-subscripts',
  '-Wformat',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
  '-Wunused-function',
  '-Wno-missing-field-initializers',
  '-Wno-unused-parameter',
  '-Wno-pedantic',
  language: 'c'
)

add_project_arguments('-DVERSION="'+meson.project_version() + '"', language : 'c')

jose = dependency('jose', version: '>=8')
a2x = find_program('a2x', required: false)
compiler = meson.get_compiler('c', native : true)

if meson.is_cross_build()
    compiler = meson.get_compiler('c', native : false)
endif

# The has_pqc probe must EXECUTE the check, not just link it: jose
# exports jose_jwk_gen and the KEM API unconditionally (lib/jwk.c) and
# registers the ML-KEM hooks only when built with them (mlkem.c), so a
# jose built with -Dmlkem=disabled links fine while the check inside
# would fail. compiler.run() executes the probe; compiler.links() is
# only a best-effort fallback for cross builds without an exe wrapper.
pqc_probe = '''
#include <jose/jose.h>
int main(void) {
    json_auto_t *j = json_pack("{s:s}", "alg", "ML-KEM-768");
    if (!jose_jwk_gen(NULL, j))
        return 1;
    json_auto_t *enc = jose_jwk_kem_enc(NULL, j);
    return enc ? 0 : 1;
}
'''

pqc_feature = get_option('pqc')
has_pqc = false

if not pqc_feature.disabled()
    # The probe must run against the jose it was configured with: a
    # prefix jose found through PKG_CONFIG_PATH only adds -L at link
    # time, so without an rpath the probe binary would load the system
    # libjose at run time and test the wrong library.
    probe_args = []
    jose_libdir = jose.get_variable(pkgconfig: 'libdir', default_value: '')
    if jose_libdir != ''
        probe_args += ['-Wl,-rpath,' + jose_libdir]
    endif

    if meson.can_run_host_binaries()
        has_pqc = compiler.run(pqc_probe, args: probe_args,
                               dependencies: jose,
                               name: 'ML-KEM KEM API support in jose').returncode() == 0
    else
        has_pqc = compiler.links(pqc_probe, dependencies: jose,
                                 name: 'ML-KEM KEM API support in jose (link-only)')
    endif

    # A quiet fallback to the noop build is only acceptable when PQC
    # support was not explicitly requested.
    if pqc_feature.enabled() and not has_pqc
        error('PQC support was requested (pqc=enabled), but jose does not provide usable ML-KEM support: the configure-time probe failed. See the meson log for details.')
    endif
endif

# libcrypto is only needed by the PQC (hybrid ML-KEM) code path: the
# noop implementation used when jose lacks ML-KEM support does not use
# OpenSSL, so the dependency is optional and only linked into tangd
# (and test-pqc) when has_pqc is true.
libcrypto = dependency('libcrypto', required: has_pqc)

message(compiler.version())
message(compiler.get_id())

http_lib = []

inc_dir = meson.get_external_property('inc_dir', '-I/usr/local/include')
lib_dir = meson.get_external_property('lib_dir','/usr/local/lib')

if meson.is_cross_build()
    message('----------------')
    message('*** THIS IS A CROSS BUILD ***')
    message('Compiler version :'+ compiler.version())
    message('Compiler ID :' + compiler.get_id())
    message('Library search directory :'+ lib_dir)
    message('Include directory :' + inc_dir)
    message('----------------')
endif

if compiler.has_header('llhttp.h', args: inc_dir)
  http_lib = 'llhttp'
  add_project_arguments('-DUSE_LLHTTP', language: 'c')
else
  if not compiler.has_header('http_parser.h', args: inc_dir)
    error('neither llhttp nor http-parser devel files found.')
  endif
  
  http_lib = 'http_parser'
endif

if host_machine.system() == 'freebsd'
  http_parser = compiler.find_library(http_lib, dirs : '/usr/local/lib')
else
  http_parser = compiler.find_library(http_lib, dirs: [lib_dir])
endif

licenses = ['COPYING']
libexecbins = []
bins = []
mans = []
units = []

subdir('doc')
subdir('src')
subdir('units')
if not meson.is_cross_build()
  subdir('tests')
endif

install_data(libexecbins, install_dir: libexecdir)
install_data(bins, install_dir: bindir)
install_data(units, install_dir: systemunitdir)
install_data(licenses, install_dir: licensedir)

if a2x.found()
  foreach m : mans
    custom_target(m.split('/')[-1], input: m + '.adoc', output: m.split('/')[-1],
      command: [a2x, '--attribute=' + build_machine.system(), '-f', 'manpage', '-D', meson.current_build_dir(), '@INPUT@'],
      install_dir: join_paths(get_option('mandir'), 'man' + m.split('.')[-1]),
      install: true
    )
  endforeach
else
  warning('Will not build man pages due to missing a2x (asciidoc) dependency!')
endif

# vim:set ts=2 sw=2 et:
