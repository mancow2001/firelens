#!/bin/bash
# Script to run unit tests for FireLens Monitor

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== FireLens Monitor Unit Tests ===${NC}\n"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment${NC}"
        exit 1
    fi
    echo -e "${GREEN}Virtual environment created${NC}\n"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to activate virtual environment${NC}"
    exit 1
fi
echo -e "${GREEN}Virtual environment activated${NC}\n"

# Install/update dependencies
echo -e "${YELLOW}Installing/updating dependencies...${NC}"
pip install -q -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to install dependencies${NC}"
    exit 1
fi
echo -e "${GREEN}Dependencies installed${NC}\n"

# Run tests based on arguments
if [ "$1" == "coverage" ]; then
    echo -e "${YELLOW}Running tests with coverage...${NC}\n"
    python -m pytest tests/ -v --cov=. --cov-report=term-missing --cov-report=html
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ All tests passed!${NC}"
        echo -e "${YELLOW}Coverage report generated in htmlcov/index.html${NC}"
    else
        echo -e "\n${RED}✗ Some tests failed${NC}"
        exit 1
    fi
elif [ "$1" == "quick" ]; then
    echo -e "${YELLOW}Running quick tests (no coverage)...${NC}\n"
    python -m pytest tests/ -v
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ All tests passed!${NC}"
    else
        echo -e "\n${RED}✗ Some tests failed${NC}"
        exit 1
    fi
elif [ "$1" == "database" ]; then
    echo -e "${YELLOW}Running database tests only...${NC}\n"
    python -m pytest tests/test_database.py -v
elif [ "$1" == "memory" ]; then
    echo -e "${YELLOW}Running memory leak tests only...${NC}\n"
    python -m pytest tests/test_memory_leaks.py -v
elif [ "$1" == "web" ]; then
    echo -e "${YELLOW}Running web dashboard tests only...${NC}\n"
    python -m pytest tests/test_web_dashboard.py -v
elif [ "$1" == "collectors" ]; then
    echo -e "${YELLOW}Running collector tests only...${NC}\n"
    python -m pytest tests/test_collectors.py -v
elif [ "$1" == "vendors" ]; then
    echo -e "${YELLOW}Running vendor abstraction tests only...${NC}\n"
    python -m pytest tests/test_vendors.py -v
else
    echo -e "${YELLOW}Running all tests...${NC}\n"
    python -m pytest tests/ -v
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ All tests passed!${NC}"
        echo -e "${YELLOW}Run './run_tests.sh coverage' for coverage report${NC}"
    else
        echo -e "\n${RED}✗ Some tests failed${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  ./run_tests.sh           - Run all tests"
echo "  ./run_tests.sh coverage  - Run with coverage report"
echo "  ./run_tests.sh quick     - Run without coverage"
echo "  ./run_tests.sh database  - Run database tests only"
echo "  ./run_tests.sh memory    - Run memory leak tests only"
echo "  ./run_tests.sh web       - Run web dashboard tests only"
echo "  ./run_tests.sh collectors - Run collector tests only"
echo "  ./run_tests.sh vendors   - Run vendor abstraction tests only"
