FROM mjonuschat/passenger-ruby25:1.0.0
MAINTAINER Morton Jonuschat <m.jonuschat@mojocode.de>

# Set correct environment variables.
ENV HOME /home/app

# Use baseimage-docker's init process.
CMD ["/sbin/my_init"]

# Start fwd-email service
COPY fwd-email.sh /etc/service/fwd-email/run

# Add the Rails app
COPY . /home/app
WORKDIR /home/app
RUN apt-get update; apt-get -y install python3 python3-dev python3-pip
RUN /usr/bin/pip3 install -r requirements.txt
RUN chown -R app:app /home/app

# Clean up APT when done
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /home/app/.image
