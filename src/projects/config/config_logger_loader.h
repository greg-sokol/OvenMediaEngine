//==============================================================================
//
//  OvenMediaEngine
//
//  Created by Gil Hoon Choi
//  Copyright (c) 2018 AirenSoft. All rights reserved.
//
//==============================================================================
#pragma once

#include "config_loader.h"

#include <base/application/logger_tag_info.h>

class ConfigLoggerLoader : public ConfigLoader
{
public:
    ConfigLoggerLoader();
    explicit ConfigLoggerLoader(const ov::String config_path);
    virtual ~ConfigLoggerLoader();

    virtual bool Parse() override;
    void Reset();

    std::vector<std::shared_ptr<LoggerTagInfo>> GetTags() const noexcept;

private:
    std::vector<std::shared_ptr<LoggerTagInfo>> _tags;
};
