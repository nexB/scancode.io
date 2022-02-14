# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

FROM --platform=linux/amd64 python:3.9

ARG USERNAME=scancodeio
ENV USERNAME=$USERNAME
ARG UID=1001
ENV UID=$UID
ARG GID=1001
ENV GID=$GID

# Python settings: Force unbuffered stdout and stderr (i.e. they are flushed to terminal immediately)
ENV PYTHONUNBUFFERED 1
# Python settings: do not write pyc files
ENV PYTHONDONTWRITEBYTECODE 1

# OS requirements as per
# https://scancode-toolkit.readthedocs.io/en/latest/getting-started/install.html
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
       bzip2 \
       xz-utils \
       zlib1g \
       libxml2-dev \
       libxslt1-dev \
       libgomp1 \
       libsqlite3-0 \
       libgcrypt20 \
       libpopt0 \
       libzstd1 \
       libgpgme11 \
       libdevmapper1.02.1 \
       libguestfs-tools \
       linux-image-amd64 \
       wait-for-it \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /opt/scancodeio/ \
             /var/scancodeio/static/ \
             /var/scancodeio/workspace/

RUN groupadd --gid ${GID} --non-unique ${USERNAME} \
 && useradd --uid ${UID} --gid ${GID} --no-create-home --home-dir=/opt/scancodeio --non-unique ${USERNAME} \
 && chown -R ${UID}:${GID} /var/scancodeio /opt \
 && chmod g+s /opt

WORKDIR /opt/scancodeio/
# Keep the dependencies installation before the COPY of the app/ for proper caching
COPY setup.cfg setup.py /opt/scancodeio/

RUN python -m venv .
ENV PATH="/opt/scancodeio/bin:$PATH"
RUN export PIP_CACHE_DIR=/tmp \
 && pip install --upgrade pip \
 && pip install .

COPY . /opt/scancodeio/
USER ${USERNAME}