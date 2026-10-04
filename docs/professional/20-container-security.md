# Container Security

For containerized execution:
- use minimal trusted base images;
- avoid running as root when unnecessary;
- copy only required files;
- keep secrets out of image layers;
- pin dependencies where practical;
- scan the resulting image;
- expose only required ports.