FROM node:12.14-alpine3.11 

# get the latest ffmpeg
#RUN apt-get update
RUN apk update


# Create app directory
WORKDIR /usr/src/autoConnectUpdateServer
# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production
# Bundle app source
COPY . .
EXPOSE 1380 1381
#CMD [ "node", "server.js" ]
CMD [ "npm", "run", "start" ]