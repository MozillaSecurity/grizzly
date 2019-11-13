FROM python:2

WORKDIR /code

RUN mkdir -p /code/browsers

# Setup FFPuppet
RUN wget -q https://github.com/MozillaSecurity/ffpuppet/archive/master.zip -O ffpuppet.zip && \
	unzip -q -x ffpuppet.zip && cd ffpuppet-master && \
	pip install --disable-pip-version-check --no-cache-dir --quiet . && \
	rm -rf /code/ffpuppet*

# Setup Lithium
RUN wget -q https://github.com/MozillaSecurity/lithium/archive/master.zip -O lithium.zip && \
	unzip -q -x lithium.zip && cd lithium-master && \
	pip install --disable-pip-version-check --no-cache-dir --quiet . && \
	rm -rf /code/lithium*

# Setup Grizzly
RUN wget -q https://github.com/MozillaSecurity/grizzly/archive/master.zip -O grizzly.zip && \
	unzip -q -x grizzly.zip && cd grizzly-master && \
	pip install --disable-pip-version-check --no-cache-dir --quiet . && \
	rm -rf /code/grizzly*

# Setup fuzzfetch
RUN wget -q https://github.com/MozillaSecurity/fuzzfetch/archive/master.zip -O fuzzfetch.zip && \
	unzip -q -x fuzzfetch.zip && cd fuzzfetch-master && \
	pip install --disable-pip-version-check --no-cache-dir --quiet . && \
	rm -rf /code/fuzzfetch*

# Download fresh firefox build at runtime
ADD docker/entrypoint.sh /code/entrypoint.sh
CMD /code/entrypoint.sh
