FROM scratch
ADD main /
COPY ssl/ ssl/
EXPOSE 9090
CMD ["/main"]