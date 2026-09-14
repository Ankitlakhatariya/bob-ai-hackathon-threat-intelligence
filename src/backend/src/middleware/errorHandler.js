/**
 * Global error handler.
 * Returns the ApiErrorBody shape expected by the frontend.
 */
const errorHandler = (err, _req, res, _next) => {
  console.error('❌', err.stack || err.message);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: messages.join('; '),
      },
    });
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    return res.status(409).json({
      error: {
        code: 'DUPLICATE_KEY',
        message: 'Resource already exists',
        details: JSON.stringify(err.keyValue),
      },
    });
  }

  // Mongoose cast error (bad ObjectId etc.)
  if (err.name === 'CastError') {
    return res.status(400).json({
      error: {
        code: 'INVALID_ID',
        message: `Invalid value for ${err.path}: ${err.value}`,
      },
    });
  }

  // Default 500
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: err.message || 'Something went wrong',
    },
  });
};

module.exports = errorHandler;
