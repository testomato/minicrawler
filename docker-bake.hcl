# Define the Docker Compose services block
# https://docs.docker.com/build/bake/reference/

####################################################################################################
# docker buildx bake --file docker-bake.hcl minicrawler --push --no-cache --progress=plain
####################################################################################################

target "minicrawler" {
  context    = "."
  dockerfile = ".docker/Dockerfile"
  target     = "minicrawler"
  platforms  = ["linux/amd64", "linux/arm64"]
  pull       = true
  # GitLab Container Registry does not support OCI attestations, without this the manifest would be corrupted
  provenance = false
  sbom       = false
  output     = ["type=image,push=true,oci-mediatypes=false"]
  tags       = [
    "gitlab.int.wikidi.net:5050/testomato/minicrawler:latest",
    "gitlab.int.wikidi.net:5050/testomato/minicrawler:v5.2.7",
  ]
}

####################################################################################################
# docker buildx bake --file docker-bake.hcl --push --no-cache --progress=plain
####################################################################################################

group "default" {
  targets = ["minicrawler"]
}