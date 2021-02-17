project('tang', 'c',
  version: '8',
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
if build_machine.system() == 'freebsd'
  licensedir += '-'+meson.project_version()
endif
jwkdir = join_paths(get_option('localstatedir'), 'db', meson.project_name())

data = configuration_data()
data.set('libexecdir', libexecdir)
data.set('sysconfdir', sysconfdir)
data.set('systemunitdir', systemunitdir)
data.set('jwkdir', jwkdir)

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

jose = dependency('jose', version: '>=8')
a2x = find_program('a2x', required: false)
compiler = meson.get_compiler('c')
if not compiler.has_header('http_parser.h',args : '-I/usr/local/include')
  error('http-parser devel files not found.')
endif
http_parser = compiler.find_library('http_parser',dirs:['/usr/lib','/usr/local/lib'])

licenses = ['COPYING']
libexecbins = []
bins = []
mans = []
units = []

subdir('doc')
subdir('src')
subdir('units')
subdir('tests')

install_data(libexecbins, install_dir: libexecdir)
install_data(bins, install_dir: bindir)
install_data(units, install_dir: systemunitdir)
install_data(licenses, install_dir: licensedir)

if a2x.found()
  foreach m : mans
    custom_target(m.split('/')[-1], input: m + '.adoc', output: m.split('/')[-1],
      command: [a2x, '-f', 'manpage', '-D', meson.current_build_dir(), '@INPUT@'],
      install_dir: join_paths(get_option('mandir'), 'man' + m.split('.')[-1]),
      install: true
    )
  endforeach
else
  warning('Will not build man pages due to missing a2x (asciidoc) dependency!')
endif

# vim:set ts=2 sw=2 et:
