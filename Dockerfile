FROM jasonish/suricata

# Update PIP
RUN yum install -y python36 python36-pip && pip3 install --upgrade pip

# Create rules dir
RUN mkdir -p /rules/

# Copy the rules into the docker image
COPY suricata_rules/ /raw_sigs/

# Copy test/compile scripts into docker image
COPY test.py /test.py
COPY compile.py /compile.py
COPY requirements.txt /requirements.txt

# Install requirements for python scripts
RUN pip3 install -r /requirements.txt

# Run Tests
RUN python3 /test.py /raw_sigs/

# Compile Ruleset
RUN python3 /compile.py /raw_sigs/ /rules/

# Remove old/raw signatures
RUN rm -rf /raw_sigs/

ENTRYPOINT ["/usr/sbin/suricata"]