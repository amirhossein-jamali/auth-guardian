#!/bin/bash

# Navigate to the docker directory
cd "$(dirname "$0")"

# Define colors for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'

# Define SSL directory
CERT_DIR="./nginx/ssl"

function show_help {
  echo -e "${YELLOW}Usage:${NC}"
  echo -e "  $0 [command]"
  echo ""
  echo -e "${YELLOW}Commands:${NC}"
  echo -e "  ${GREEN}start${NC}     - Start the services (default)"
  echo -e "  ${GREEN}stop${NC}      - Stop all services"
  echo -e "  ${GREEN}restart${NC}   - Restart all services"
  echo -e "  ${GREEN}rebuild${NC}   - Rebuild and restart services (removes containers but keeps volumes)"
  echo -e "  ${GREEN}clean${NC}     - Remove all containers and volumes (WARNING: deletes all data!)"
  echo -e "  ${GREEN}logs${NC}      - Show logs for all services"
  echo -e "  ${GREEN}status${NC}    - Show status of all services"
  echo -e "  ${GREEN}migrate${NC}   - Run database migrations"
  echo -e "  ${GREEN}ssl-dev${NC}   - Generate self-signed SSL certificate for development"
  echo -e "  ${GREEN}ssl-prod${NC}  - Setup Let's Encrypt SSL for production (requires domain argument)"
  echo -e "  ${GREEN}start-ssl${NC} - Setup dev SSL certificate and start services"
  echo -e "  ${GREEN}help${NC}      - Show this help message"
}

function start_services {
  echo -e "${GREEN}Starting services...${NC}"
  docker-compose up -d
  echo -e "${GREEN}Services started successfully!${NC}"
}

function stop_services {
  echo -e "${YELLOW}Stopping services...${NC}"
  docker-compose down
  echo -e "${GREEN}Services stopped.${NC}"
}

function restart_services {
  echo -e "${YELLOW}Restarting services...${NC}"
  docker-compose down
  docker-compose up -d
  echo -e "${GREEN}Services restarted successfully!${NC}"
}

function rebuild_services {
  echo -e "${YELLOW}Rebuilding services...${NC}"
  docker-compose down
  docker-compose build --no-cache
  docker-compose up -d
  echo -e "${GREEN}Services rebuilt and started successfully!${NC}"
}

function clean_environment {
  echo -e "${RED}WARNING: This will remove all containers, images and volumes associated with this project!${NC}"
  read -p "Are you sure you want to continue? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Cleaning environment...${NC}"
    docker-compose down -v --rmi all --remove-orphans
    echo -e "${GREEN}Environment cleaned.${NC}"
  else
    echo -e "${YELLOW}Operation cancelled.${NC}"
  fi
}

function show_logs {
  echo -e "${GREEN}Showing logs (press Ctrl+C to exit):${NC}"
  docker-compose logs -f
}

function show_status {
  echo -e "${GREEN}Services status:${NC}"
  docker-compose ps
}

function run_migrations {
  echo -e "${YELLOW}Running database migrations...${NC}"
  # Check if API container is running
  if [ "$(docker-compose ps -q api)" ]; then
    # Execute the migration command inside the API container
    docker-compose exec api ./main migrate
    echo -e "${GREEN}Migrations completed.${NC}"
  else
    echo -e "${RED}API container is not running. Start services first.${NC}"
    exit 1
  fi
}

# SSL Functions from setup-ssl.sh

function generate_dev_cert {
  echo -e "${YELLOW}Generating self-signed certificate for development...${NC}"
  mkdir -p $CERT_DIR
  
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout $CERT_DIR/server.key -out $CERT_DIR/server.crt \
    -subj "//CN=localhost" \
    -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"
  
  chmod 644 $CERT_DIR/server.crt
  chmod 600 $CERT_DIR/server.key
  
  echo -e "${GREEN}Self-signed certificate generated successfully at $CERT_DIR/${NC}"
  echo -e "${YELLOW}WARNING: Self-signed certificates are only suitable for development/testing${NC}"
}

function setup_letsencrypt {
  if [ -z "$1" ]; then
    echo -e "${RED}Error: Domain name is required for production deployment${NC}"
    echo -e "${YELLOW}Usage: $0 ssl-prod domain.com [email]${NC}"
    exit 1
  fi
  
  DOMAIN=$1
  EMAIL=$2
  
  echo -e "${YELLOW}Setting up Let's Encrypt certificates for domain: $DOMAIN${NC}"
  mkdir -p $CERT_DIR
  mkdir -p ./nginx/letsencrypt
  
  echo -e "${GREEN}1. Install certbot on your host system (not in Docker):${NC}"
  echo -e "   For Ubuntu/Debian: sudo apt-get install certbot"
  echo -e "   For CentOS/RHEL: sudo yum install certbot"
  
  echo -e "${GREEN}2. Run certbot to obtain certificates:${NC}"
  if [ -z "$EMAIL" ]; then
    echo -e "   sudo certbot certonly --standalone -d $DOMAIN --agree-tos --non-interactive --preferred-challenges http"
  else
    echo -e "   sudo certbot certonly --standalone -d $DOMAIN --agree-tos --non-interactive --preferred-challenges http --email $EMAIL"
  fi
  
  echo -e "${GREEN}3. Copy certificates to the nginx/ssl directory:${NC}"
  echo -e "   sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/server.crt"
  echo -e "   sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/server.key"
  
  echo -e "${GREEN}4. Set proper permissions:${NC}"
  echo -e "   sudo chmod 644 $CERT_DIR/server.crt"
  echo -e "   sudo chmod 600 $CERT_DIR/server.key"
  
  echo -e "${GREEN}5. Create a cron job to auto-renew the certificate:${NC}"
  echo -e "   echo '0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/server.crt && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/server.key' | sudo tee -a /etc/crontab > /dev/null"
  
  echo ""
  echo -e "${YELLOW}Follow these steps manually to set up Let's Encrypt certificates${NC}"
  echo ""
  echo -e "${GREEN}After completing these steps, start the services with:${NC} $0 start"
}

function start_with_ssl {
  echo -e "${YELLOW}Setting up development SSL and starting services...${NC}"
  generate_dev_cert
  start_services
  echo -e "${GREEN}Application is now running with HTTPS at https://localhost${NC}"
  echo -e "${BLUE}This server supports HTTP/1.1, HTTP/2, and HTTP/3 protocols.${NC}"
  echo -e "To check if you're using HTTP/3:"
  echo -e "1. Open Developer Tools in your browser (F12)"
  echo -e "2. Go to Network tab and enable Protocol column"
  echo -e "3. Look for 'h3' protocol when accessing your site"
  echo -e "\nLearn more about HTTP/3 setup in the ${YELLOW}HTTP3_README.md${NC} file."
}

# Check for .env file
if [ ! -f ./.env ]; then
  echo -e "${RED}Error: .env file not found in $(pwd)${NC}"
  echo -e "${YELLOW}Please create a .env file with required environment variables.${NC}"
  exit 1
fi

# Process command line arguments
COMMAND=${1:-start}

case "$COMMAND" in
  start)
    start_services
    ;;
  stop)
    stop_services
    ;;
  restart)
    restart_services
    ;;
  rebuild)
    rebuild_services
    ;;
  clean)
    clean_environment
    ;;
  logs)
    show_logs
    ;;
  status)
    show_status
    ;;
  migrate)
    run_migrations
    ;;
  ssl-dev)
    generate_dev_cert
    ;;
  ssl-prod)
    setup_letsencrypt "$2" "$3"
    ;;
  start-ssl)
    start_with_ssl
    ;;
  help)
    show_help
    ;;
  *)
    echo -e "${RED}Unknown command: $COMMAND${NC}"
    show_help
    exit 1
    ;;
esac