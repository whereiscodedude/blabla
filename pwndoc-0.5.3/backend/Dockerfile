FROM node:lts-alpine AS build

WORKDIR /app

COPY package*.json ./

RUN apk --no-cache add --virtual builds-deps build-base python3 git && \
    npm install && \
    apk del builds-deps

COPY . .

EXPOSE 4242

CMD ["npm", "start"]
