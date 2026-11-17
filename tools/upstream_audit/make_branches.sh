#!/bin/bash
# Build one branch per patch from master inside the audit container, check each, and bundle them
# for the push to the fork (see file_upstream.py for the merge requests).
#
#   make_branches.sh "NN branch" ...
#
# /w/patches holds copies of docs/upstream/frama-c/patches (docker cp, chown -R opam /w,
# chmod 644). Run as the user opam. A branch that already exists for NN is kept as it is when
# its name is passed with KEEP=NN (a commit made by hand in the container, as for a manual fix).
#
# Each branch must be the commits of its patch on master, with the file count of the patch, no
# file-mode change, and author and committer both set to the GitLab noreply identity: the image's
# own git identity is `audit`, and `git am` would use it as the committer.
#
# Then, on the host (whose clones convert line endings, so nothing is applied there):
#   docker cp <container>:/w/branches.bundle .
#   git -C <clone of pub/frama-c> fetch branches.bundle '+refs/heads/*:refs/remotes/bundle/*'
#   git -C <clone> push <fork url> refs/remotes/bundle/<branch>:refs/heads/<branch> ...
set -u
ID=1315-Harvester57@users.noreply.git.frama-c.com
cd /home/opam/frama-c || exit 2
base=$(git rev-parse master)
git config user.name "Florian Stosse"
git config user.email "$ID"
bad=0
branches=
for spec in "$@"; do
  nn=${spec%% *}; br=${spec#* }
  patch=$(ls /w/patches/"$nn"-*.patch | head -n 1)
  if [ "${KEEP:-}" != "$nn" ]; then
    git checkout -q -f master && git clean -fdq && git checkout -q -B "$br" master || { bad=1; continue; }
    git am -q --keep-non-patch "$patch" || { echo "FAIL am $nn"; git am --abort; bad=1; continue; }
  fi
  n=$(git rev-list --count master.."$br")
  want=$(grep -c -E '^From [0-9a-f]{40} ' "$patch")
  modes=$(git diff --summary master.."$br" | grep -c -E 'mode change|create mode 100755')
  ids=$(git log --format='%ae %ce' master.."$br" | sort -u | tr '\n' ' ')
  mb=$(git merge-base master "$br")
  subj=$(git log -1 --format=%s "$br")
  files=$(git diff --name-only master.."$br" | wc -l)
  pfiles=$(grep -c '^diff --git ' "$patch")
  ok=ok
  [ "$n" = "$want" ] && [ "$modes" = 0 ] && [ "$mb" = "$base" ] && [ "$files" = "$pfiles" ] \
    && [ "$ids" = "$ID $ID " ] || { ok=BAD; bad=1; }
  echo "$ok $nn $br $(git rev-parse --short "$br") commits=$n/$want files=$files/$pfiles modes=$modes tree=$(git rev-parse --short "$br^{tree}") | $subj"
  branches="$branches $br"
done
git checkout -q -f master
[ "$bad" = 0 ] || { echo "NOT BUNDLED"; exit 1; }
rm -f /w/branches.bundle
git bundle create /w/branches.bundle ^master $branches 2>&1 | tail -n 2
git bundle list-heads /w/branches.bundle
