srpm:
	dnf install -y git
	git config --global --add safe.directory ${PWD}
	./build.sh --with-timestamp --with-commit-id --builder=mvn srpm
	if [[ "${outdir}" != "" ]]; then \
	    mv ${HOME}/build/pki/SRPMS/* ${outdir}; \
	fi
