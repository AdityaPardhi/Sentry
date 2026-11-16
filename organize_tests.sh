#!/usr/bin/env bash
set -e
S=tests/samples
mkdir -p $S/safe $S/harmful/behaviour $S/harmful/resource-abuse $S/harmful/seccomp

mv_() {  # mv_ <file> <dest-folder>
  git mv "tests/$1" "$2/$1" 2>/dev/null || mv "tests/$1" "$2/$1"
  sed -i "s#\$(TESTS)/$1#\$(TESTS)/${2#tests/}/$1#g; s#tests/$1#$2/$1#g" Makefile tests/test_phase*.sh
}

mv_ t1_clean.c           $S/safe
for f in t2_file_drop t3_secret_reader t4_network t5_spawner; do mv_ $f.c $S/harmful/behaviour; done
for f in stress_cpu stress_mem stress_fork stress_files stress_net; do mv_ $f.c $S/harmful/resource-abuse; done
mv_ test_seccomp_block.c $S/harmful/seccomp

make -n >/dev/null && echo "OK: Makefile paths resolve" || echo "Makefile problem - check paths"
find $S -type f | sort
