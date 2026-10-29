FROM quay.io/fedora/fedora:latest AS build
RUN dnf -y --setopt=deltarpm=0 update && \
    dnf -y install gcc pkgconfig meson libjose-devel jose llhttp-devel
RUN mkdir -p /build/in /build/out
COPY . /build/in/
WORKDIR /build/out
RUN meson setup ../in && ninja-build

FROM quay.io/fedora/fedora:latest AS runtime
RUN dnf -y install jose llhttp
COPY src/tang-show-keys /bin/
COPY --from=build /build/out/src/tangd /build/out/src/tangd-rotate-keys /build/out/src/tangd-keygen /bin/

VOLUME [ "/jwkdir" ]
EXPOSE 9090

CMD [ "/bin/tangd", "-l", "-p", "9090", "/jwkdir" ]