project('tang', 'c',
  version: '15',
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
    message('Include directiry :' + inc_dir)
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
subdir('tests')

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
