#!/bin/bash
# Quick benchmark runner for MacBook Pro testing
# This script helps test hardware acceleration on macOS

set -e

echo "🚀 Armoricore Media Processor Benchmarks"
echo "=========================================="
echo ""

# Check if FFmpeg is installed
if ! command -v ffmpeg &> /dev/null; then
    echo "❌ FFmpeg is not installed"
    echo "   Install with: brew install ffmpeg"
    exit 1
fi

echo "✅ FFmpeg found: $(ffmpeg -version | head -1)"
echo ""

# Check VideoToolbox support
echo "🔍 Checking VideoToolbox hardware acceleration..."
if ffmpeg -encoders 2>&1 | grep -q "h264_videotoolbox"; then
    echo "✅ h264_videotoolbox: Available"
else
    echo "❌ h264_videotoolbox: Not available"
fi

if ffmpeg -encoders 2>&1 | grep -q "hevc_videotoolbox"; then
    echo "✅ hevc_videotoolbox: Available"
else
    echo "❌ hevc_videotoolbox: Not available"
fi

if ffmpeg -encoders 2>&1 | grep -q "av1_videotoolbox"; then
    echo "✅ av1_videotoolbox: Available"
else
    echo "❌ av1_videotoolbox: Not available"
fi

echo ""
echo "📊 Running simple benchmark..."
echo ""

# Run the simple benchmark
cargo bench --bench simple_benchmark

echo ""
echo "✅ Benchmark complete!"
echo ""
echo "To run full benchmarks:"
echo "  cargo bench --bench encoding_benchmarks"

