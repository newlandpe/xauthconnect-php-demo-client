<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $pageTitle ?></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.5.0/dist/semantic.min.css">
    <style>
        body {
            background: #f5f5f5;
            padding: 20px;
        }
        .ui.container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        h1.ui.header {
            color: #333;
            margin-bottom: 30px;
            font-size: 28px;
            font-weight: 600;
        }
        pre {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="ui container">
        <h1 class="ui header">🔐 XAuthConnect Demo Client</h1>

        <?php if (!empty($error)): ?>
            <div class="ui negative message">
                <div class="header">Error:</div>
                <p><?= htmlspecialchars($error) ?></p>
            </div>
        <?php endif; ?>

        <?php if (!empty($success)): ?>
            <div class="ui positive message">
                <div class="header">Success:</div>
                <p><?= htmlspecialchars($success) ?></p>
            </div>
        <?php endif; ?>