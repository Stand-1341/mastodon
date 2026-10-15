# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'PQC messaging route' do
  it 'routes direct loads to the React application shell' do
    expect(get('/pqc')).to route_to('home#index')
  end
end
