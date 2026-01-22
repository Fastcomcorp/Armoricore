#!/bin/bash
# Fastcomcorp License Requirements Checker
# Helps users determine if they need a commercial license for Armoricore

echo "🔍 Fastcomcorp Armoricore License Requirements Checker"
echo "======================================================"
echo ""

echo "This tool will help you determine if your use case requires a commercial license."
echo "Answer the following questions to check your licensing requirements."
echo ""

# Question 1: Revenue generation
echo "Question 1: Will your application generate revenue?"
echo "Examples: Selling the app, subscription fees, advertising, premium features"
echo "1) Yes, directly (selling the app/service)"
echo "2) Yes, indirectly (advertising, data monetization)"
echo "3) No, it's completely free"
read -p "Your answer (1-3): " revenue

# Question 2: Business use
echo ""
echo "Question 2: Is this for business/enterprise use?"
echo "Examples: Company communication, customer support, internal tools"
echo "1) Yes, for my company/business"
echo "2) Yes, for a client/company"
echo "3) No, personal/individual use only"
read -p "Your answer (1-3): " business

# Question 3: Scale
echo ""
echo "Question 3: What's your expected scale?"
echo "1) Large scale (100+ users, high traffic)"
echo "2) Medium scale (10-99 users)"
echo "3) Small scale (1-9 users, personal)"
read -p "Your answer (1-3): " scale

# Question 4: Distribution
echo ""
echo "Question 4: Will you distribute or sell this application?"
echo "Examples: App store, SaaS platform, white-label solution"
echo "1) Yes, as a commercial product/service"
echo "2) Yes, but only free distribution"
echo "3) No distribution, internal use only"
read -p "Your answer (1-3): " distribution

echo ""
echo "📊 Analysis Results"
echo "==================="

commercial_score=0

# Scoring logic
if [ "$revenue" = "1" ] || [ "$revenue" = "2" ]; then
    commercial_score=$((commercial_score + 3))
    echo "💰 Revenue generation detected (+3 points)"
fi

if [ "$business" = "1" ] || [ "$business" = "2" ]; then
    commercial_score=$((commercial_score + 3))
    echo "🏢 Business/enterprise use detected (+3 points)"
fi

if [ "$scale" = "1" ]; then
    commercial_score=$((commercial_score + 2))
    echo "📈 Large scale deployment (+2 points)"
elif [ "$scale" = "2" ]; then
    commercial_score=$((commercial_score + 1))
    echo "📊 Medium scale deployment (+1 point)"
fi

if [ "$distribution" = "1" ]; then
    commercial_score=$((commercial_score + 3))
    echo "📦 Commercial distribution detected (+3 points)"
fi

echo ""
echo "🎯 License Recommendation"
echo "========================="

if [ $commercial_score -ge 5 ]; then
    echo "💼 COMMERCIAL LICENSE REQUIRED"
    echo ""
    echo "Based on your answers, your use case requires a commercial license."
    echo "Commercial licenses start at \$4,999/year for small businesses."
    echo ""
    echo "Next steps:"
    echo "1. Visit: https://fastcomcorp.com/licensing"
    echo "2. Email: licensing@fastcomcorp.com"
    echo "3. Request a 30-day evaluation license"
elif [ $commercial_score -ge 2 ]; then
    echo "⚠️  COMMERCIAL LICENSE RECOMMENDED"
    echo ""
    echo "Your use case may require a commercial license. We recommend contacting us for clarification."
    echo ""
    echo "Contact: licensing@fastcomcorp.com"
else
    echo "🆓 PERSONAL USE LICENSE SUFFICIENT"
    echo ""
    echo "Your use case qualifies for free personal use under the Fastcomcorp Commercial License."
    echo "You can use Armoricore freely for personal, non-commercial purposes."
fi

echo ""
echo "📋 Commercial License Options:"
echo "• Small Business: \$4,999/year (up to 100 users)"
echo "• Enterprise: \$24,999/year (up to 1,000 users)"
echo "• Unlimited: \$99,999/year (unlimited users)"
echo "• OEM/White-label: Custom pricing"

echo ""
echo "❓ Questions? Contact licensing@fastcomcorp.com"
echo ""
echo "📖 Full licensing details: COMMERCIAL_LICENSE_README.md"
echo "🔗 Website: https://fastcomcorp.com/licensing"