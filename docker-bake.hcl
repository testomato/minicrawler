# Define the Docker Compose services block
# https://docs.docker.com/build/bake/reference/

####################################################################################################
# docker buildx bake --file docker-bake.hcl minicrawler --push --no-cache --progress=plain
####################################################################################################

target "minicrawler" {
  args = {
    MINICRAWLER_VERSION = "v5.2.6"
  }
  context    = "git@gitlab.int.wikidi.net:testomato/minicrawler.git"
  dockerfile = ".docker/minicrawler/Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  ssh        = ["default"]
  pull       = true
  tags       = [
    "dr.brzy.cz/testomato/minicrawler:latest",
    "dr.brzy.cz/testomato/minicrawler:v5.2.6",
  ]
}

####################################################################################################
# docker buildx bake --file docker-bake.hcl --push --no-cache --progress=plain
####################################################################################################

group "default" {
  targets = ["minicrawler"]
}