Summary: stroprototrace
Name: stroprototrace
Version: 1.0
Release: 1
License: non open source，The copyright belongs to KylinSoft Co.,Ltd.
Source: stroprototrace.tar.gz
Excludearch: loongarch64 mips64el
BuildRequires: make CLI11-devel libbpf-devel bpftool clang > 17.0 xfsprogs-devel e2fsprogs-devel lvm2-devel
Requires: libbpf

%description
stroprototrace

%prep
%setup -n %{name}

%build
%cmake
%make_build

%install
%make_install

%files
%{_bindir}/%{name}

%changelog
* Fri Nov 8 2024 yanshuai <yanshuai01@kylinos.cn> - 1.0-1
- Type:compile
- ID:NA
- SUG:NA
- DESC: init
