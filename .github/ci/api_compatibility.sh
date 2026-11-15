#!/usr/bin/env bash
# Compares a module's jar with its newest release on Maven Central that has the
# same major version, using japicmp, and writes api-compatibility/<module>.html.
# Report only: it exits 0 whatever japicmp finds. Before the first release of
# that major version there is nothing to compare, and it says so.
#
# Usage: api_compatibility.sh <module dir>
set -euo pipefail

module=$1
japicmp_version=0.27.0
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}

properties=$(./gradlew -q -p "$module" properties)
group=$(sed -n 's/^group: //p' <<<"$properties")
name=$(sed -n 's/^name: //p' <<<"$properties")
version=$(sed -n 's/^version: //p' <<<"$properties")
major=${version%%.*}

metadata=$(curl -sSf "https://repo1.maven.org/maven2/${group//.//}/$name/maven-metadata.xml" || true)
release=$(grep -o '<version>[^<]*</version>' <<<"$metadata" | sed 's/<[^>]*>//g' \
  | grep -E "^$major\.[0-9]+\.[0-9]+$" | sort -V | tail -n 1 || true)
if [ -z "$release" ]; then
  echo "$group:$name has no $major.x release on Maven Central, so there is no API to compare $version with." | tee -a "$summary"
  exit 0
fi

./gradlew -q -p "$module" jar
jar=$(find "$module/build/libs" -name "$name-$version.jar" | head -n 1)
curl -sSfLo old.jar "https://repo1.maven.org/maven2/${group//.//}/$name/$release/$name-$release.jar"
curl -sSfLo japicmp.jar "https://repo1.maven.org/maven2/com/github/siom79/japicmp/japicmp/$japicmp_version/japicmp-$japicmp_version-jar-with-dependencies.jar"
mkdir -p api-compatibility
java -jar japicmp.jar --old old.jar --new "$jar" --only-modified \
  --html-file "api-compatibility/$module.html" > "api-compatibility/$module.txt"
{ echo "### API changes in $module since $release (report only)"; echo '```'; cat "api-compatibility/$module.txt"; echo '```'; } >> "$summary"
